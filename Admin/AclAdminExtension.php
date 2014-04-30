<?php

/*
 * (c) La Coopérative des Tilleuls <contact@les-tilleuls.coop>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 *
 * (c) JUILLARD YOANN <juillard.yoann@gmail.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE2.
 *
 * (c) Stephen Leavitt <stephen.leavitt@sonyatv.com>
 */

namespace CoopTilleuls\Bundle\AclSonataAdminExtensionBundle\Admin;

use Sonata\AdminBundle\Admin\AdminExtension;
use Sonata\AdminBundle\Admin\AdminInterface;
use Sonata\AdminBundle\Datagrid\ProxyQueryInterface;
use Doctrine\DBAL\Connection;
use Symfony\Component\Security\Acl\Permission\MaskBuilder;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;

/**
 * Admin extension filtering the list
 *
 * @author Kévin Dunglas <kevin@les-tilleuls.coop>
 * @author JUILLARD YOANN <juillard.yoann@gmail.com>
 * @author Stephen Leavitt <stephen.leavitt@sonyatv.com>
 */
class AclAdminExtension extends AdminExtension
{
    /**
     * @var SecurityContextInterface
     */
    protected $securityContext;
    /**
     * @var Connection
     */
    protected $databaseConnection;

    /**
     * @param SecurityContextInterface $securityContext
     * @param Connection               $databaseConnection
     */
    public function __construct(SecurityContextInterface $securityContext, Connection $databaseConnection)
    {
        $this->securityContext = $securityContext;
        $this->databaseConnection = $databaseConnection;
    }

    /**
     * Filters with ACL
     *
     * @param  AdminInterface      $admin
     * @param  ProxyQueryInterface $query
     * @param  string              $context
     * @throws \RuntimeException
     */
    public function configureQuery(AdminInterface $admin, ProxyQueryInterface $query, $context = 'list')
    {
        // Don't filter for admins and for not ACL enabled classes and for command cli
        if ((!$admin->isAclEnabled() && !method_exists($admin, 'getMasterAclClass')) || !$this->securityContext->getToken() || $admin->isGranted(sprintf($admin->getSecurityHandler()->getBaseRole($admin), 'ADMIN'))) {
            return;
        }

        // Retrieve current logged user SecurityIdentity
        $user = $this->securityContext->getToken()->getUser();
        $securityIdentity = UserSecurityIdentity::fromAccount($user);

        // Get identity ACL identifier
        $identifier = sprintf('%s-%s', $securityIdentity->getClass(), $securityIdentity->getUsername());

        $identityStmt = $this->databaseConnection->prepare('SELECT id FROM acl_security_identities WHERE identifier = :identifier');
        $identityStmt->bindValue('identifier', $identifier, \PDO::PARAM_STR);
        $identityStmt->execute();

        $identityId = $identityStmt->fetchColumn();

        // Get class ACL identifier
        $classType = $admin->getClass();
        $classStmt = $this->databaseConnection->prepare('SELECT id FROM acl_classes WHERE class_type = :classType');
        $classStmt->bindValue('classType', $classType, \PDO::PARAM_STR);
        $classStmt->execute();
        $classId = $classStmt->fetchColumn();

        if ($identityId && ($classId || method_exists($admin, 'getMasterAclClass'))) {
            $entriesStmt = $this->databaseConnection->prepare('SELECT aoi.object_identifier FROM acl_entries AS ae JOIN acl_object_identities AS aoi ON ae.object_identity_id = aoi.id WHERE ae.class_id = :classId AND ae.security_identity_id = :identityId AND (:view = ae.mask & :view OR :operator = ae.mask & :operator OR :master = ae.mask & :master OR :owner = ae.mask & :owner)');
            $entriesStmt->bindValue('classId', $classId, \PDO::PARAM_INT);
            $entriesStmt->bindValue('identityId', $identityId, \PDO::PARAM_INT);
            $entriesStmt->bindValue('view', MaskBuilder::MASK_VIEW, \PDO::PARAM_INT);
            $entriesStmt->bindValue('operator', MaskBuilder::MASK_OPERATOR, \PDO::PARAM_INT);
            $entriesStmt->bindValue('master', MaskBuilder::MASK_MASTER, \PDO::PARAM_INT);
            $entriesStmt->bindValue('owner', MaskBuilder::MASK_OWNER, \PDO::PARAM_INT);
            $entriesStmt->execute();

            $ids = array();
            foreach ($entriesStmt->fetchAll() as $row) {
                $ids[] = $row['object_identifier'];
            }

            // Test if method getMasterAclClass and getMasterAclPath exist on the admin CLASS -> SEE THE DOC
            if (method_exists($admin, 'getMasterAclClass') && method_exists($admin, 'getMasterAclPath')) {
                $classStmt = $this->databaseConnection->prepare('SELECT id FROM acl_classes WHERE class_type = :classType');
                // QUERY ON MASTER ACL CLASS (method $admin->getMasterAclClass() return a string like 'Acme\Bundle\Entity\MasterACLEntity');
                $classStmt->bindValue('classType', $admin->getMasterAclClass(), \PDO::PARAM_STR);
                $classStmt->execute();

                $classId = $classStmt->fetchColumn();

                $entriesStmt = $this->databaseConnection->prepare('SELECT aoi.object_identifier FROM acl_entries AS ae JOIN acl_object_identities AS aoi ON ae.object_identity_id = aoi.id WHERE ae.class_id = :classId AND ae.security_identity_id = :identityId AND (:view = ae.mask & :view OR :operator = ae.mask & :operator OR :master = ae.mask & :master OR :owner = ae.mask & :owner)');
                $entriesStmt->bindValue('classId', $classId, \PDO::PARAM_INT);
                $entriesStmt->bindValue('identityId', $identityId, \PDO::PARAM_INT);
                $entriesStmt->bindValue('view', MaskBuilder::MASK_VIEW, \PDO::PARAM_INT);
                $entriesStmt->bindValue('operator', MaskBuilder::MASK_OPERATOR, \PDO::PARAM_INT);
                $entriesStmt->bindValue('master', MaskBuilder::MASK_MASTER, \PDO::PARAM_INT);
                $entriesStmt->bindValue('owner', MaskBuilder::MASK_OWNER, \PDO::PARAM_INT);
                $entriesStmt->execute();

                // ARRAY OF idsMaster
                $idsMaster = array();
                foreach ($entriesStmt->fetchAll() as $row) {
                    $idsMaster[] = $row['object_identifier'];
                }

                $parents = $admin->getMasterAclPath();

                // HERE UPDATE THE QUERY
                foreach ($parents as $key => $parent) {
                    // FIRST shorcut is 'o'
                    if ($key == 0) {
                        $query->leftJoin('o.'.$parent[0], $parent[1]);
                    } else {
                        // Shortcut is precedent shortcut
                        $query->leftJoin($parents[$key-1][1].'.'.$parent[0], $parent[1]);
                    }
                    // HERE WE ARE AFTER THE LEFT JOIN ON MASTER ACL CLASS WE PASS idsMaster array param
                    if (($key + 1) == count($parents)) {
                        // HERE FOR OBJECT CREATED BY CURRENT USER AND WITH STRICT MODE IS OF
                        if (count($ids) && method_exists($admin, 'getMasterAclStrict') && !$admin->getMasterAclStrict()){
                            // OR EXPRESSION WITH PARENTHESIS
                            $orCondition = $query->expr()->orx();
                            $orCondition->add($query->expr()->in('o.id', ':ids'));
                            $orCondition->add($query->expr()->in($parent[1].'.id',':idsMaster'));
                            $query->andWhere($orCondition)->setParameter('ids', $ids)->setParameter('idsMaster', $idsMaster);
                        } else {
                            $query->andWhere($parent[1].'.id IN (:idsMaster'.$key.')')->setParameter('idsMaster'.$key, $idsMaster);
                        }
                    }
                }

                return;
            } elseif (count($ids)) {
                // NORMAL BEHAVIOR
                $query
                    ->andWhere('o.id IN (:ids)')
                    ->setParameter('ids', $ids)
                ;

                return;
            }
        }

        // Display an empty list
        $query->andWhere('1 = 2');
    }
}
